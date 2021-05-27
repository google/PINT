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

#include "fmd/parse.h"
#include "fmd/util.h"

#include <string.h>

int parse_region_info(struct payload_region_info *region_info, struct image_descriptor *descriptor) {
  if (region_info->tlv.version != PAYLOAD_REGION_INFO_VERSION) {
    return FMD_ERROR_UNKNOWN_VERSION;
  }

  memcpy(&descriptor->region_info, region_info, sizeof(struct payload_region_info));

  return FMD_SUCCESS;
}

int parse_payload_region(struct payload_region *region, uint32_t region_idx,
                         struct image_descriptor *descriptor) {

  if (region->tlv.version != PAYLOAD_REGION_VERSION) {
    return FMD_ERROR_UNKNOWN_VERSION;
  }

  if (region_idx >= MAX_REGION_COUNT) {
    return FMD_ERROR_INVALID_FORMAT;
  }

  memcpy(&descriptor->regions[region_idx], region, sizeof(struct payload_region));

  return FMD_SUCCESS;
}

int parse_header(struct payload_descriptor_header *header, struct image_descriptor *descriptor) {
  if (header->tlv.version != PAYLOAD_DESCRIPTOR_HEADER_VERSION) {
    return FMD_ERROR_UNKNOWN_VERSION;
  }

  // Header is assumed to be the first TLV structure. Fail if this structure is
  // not the descriptor header.
  if (header->tlv.tag != PAYLOAD_DESCRIPTOR_HEADER_TAG ||
      header->magic != FMD_MAGIC) {
    return FMD_ERROR_INVALID_FORMAT;
  }

  memcpy(&descriptor->header, desc_header, sizeof(struct payload_descriptor_header));
}

int parse_descriptor(void *flash_addr, struct image_descriptor *descriptor) {
  int rc = parse_header((struct payload_descriptor_header *)flash_addr, descriptor);

  // Loop through TLV sections. Handle those which are known to this parser,
  // while skipping any unknown sections.
  uint32_t region_idx = 0;
  void *offset = flash_addr + descriptor->header.tlv.length;
  while (offset < flash_addr + descriptor->header.descriptor_area_size) {
    struct tlv_header *tlv = (struct tlv_header*)offset;

    switch (tlv->tag) {
      case PAYLOAD_REGION_INFO_TAG:
        rc = parse_region_info((struct payload_region_info *)offset, descriptor);
        break;
      case PAYLOAD_REGION_TAG:
        rc = parse_payload_region((struct payload_region *)offset, region_idx,
                                  descriptor);
        region_idx++;
        break;
      default:
        // Skip any unknown sections
        rc = FMD_SUCCESS;
        break;
    }

    if (rc != FMD_SUCCESS) {
      return rc;
    }

    offset += tlv->length;
  }

  // Number of region TLVs found in the descriptor must match the region count
  if (descriptor->region_info.region_count != region_idx) {
    return FMD_ERROR_INVALID_FORMAT;
  }

  return FMD_SUCCESS;
}
