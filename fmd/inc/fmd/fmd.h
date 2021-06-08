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

#ifndef __FMD_H
#define __FMD_H

#include <stddef.h>
#include <stdint.h>

/**
 *  ---------------------------------- Layout ----------------------------------
 *  |                             struct fmd_header                            |
 *  ----------------------------------------------------------------------------
 *  |                         struct fmd_region_info                           |
 *  ----------------------------------------------------------------------------
 *  |                 struct fmd_region[fmd_region_info.region_count]          |
 *  ----------------------------------------------------------------------------
 */

#define FMD_HASH_SHA1 0
#define FMD_HASH_SHA256 1

#define FMD_HEADER_TAG 0
#define FMD_REGION_INFO_TAG 1
#define FMD_REGION_TAG 2

#define FMD_REGION_INFO_VERSION 1
#define FMD_REGION_VERSION 1
#define FMD_HEADER_VERSION 1

#define FMD_MAGIC 0xAABBCCDD

struct tlv_header {
  uint32_t tag;
  uint16_t length;
  uint8_t version; // version of the struct in which this header is embedded.
};

struct fmd_region_info {
  struct tlv_header tlv;

  uint32_t region_count;

  uint32_t hash_type;
};

struct fmd_region {
  struct tlv_header tlv;

  uint8_t region_name[32];  /* null-terminated ASCII string */

  uint32_t region_offset;

  uint32_t region_size;
};

struct fmd_header {
  struct tlv_header tlv;

  uint32_t magic;

  /* The offset is relative to the start of the image data. */
  uint32_t descriptor_offset;

  /* Includes this struct as well as the auxiliary structs. This many bytes
   * will be skipped when computing the hash of the region this struct
   * resides in. Tail padding is allowed but must be all 0xff's.
   */
  uint32_t descriptor_area_size;
};

#endif // __FMD_H
