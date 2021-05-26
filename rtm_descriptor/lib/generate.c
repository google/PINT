#include "fmd/generate.h"

#include <string.h>

int create_descriptor(const struct payload_region* regions, size_t region_count,
                      int hash_type, struct image_descriptor *out) {
  // Populate header
  out->header.tlv.tag = PAYLOAD_DESCRIPTOR_HEADER_TAG;
  out->header.tlv.length = sizeof(out->header);
  out->header.tlv.version = PAYLOAD_DESCRIPTOR_HEADER_VERSION;
  out->header.descriptor_offset = 0;
  out->header.descriptor_area_size = sizeof(out->header) +
                                     sizeof(out->region_info) +
                                     (region_count * sizeof(struct payload_region));

  // Populate region info
  out->region_info.tlv.tag = PAYLOAD_REGION_INFO_TAG;
  out->region_info.tlv.length = sizeof(out->region_info);
  out->region_info.tlv.version = PAYLOAD_REGION_INFO_VERSION;
  out->region_info.region_count = region_count;
  out->region_info.hash_type = hash_type;

  memcpy(out->regions, regions, sizeof(struct payload_region) * region_count);

  return FMD_SUCCESS;
}

