#include <string.h>

#include "payload_descriptor.h"

#define MAX_REGION_COUNT 0xFF

#define DESCRIPTOR_FLASH_ADDR 0x0
#define IMAGE_REGION_BASE 0x1000


struct image_descriptor {
  struct payload_descriptor_header header;
  struct payload_region_info region_info;
  struct payload_region regions[MAX_REGION_COUNT];
};

static const struct tlv_header region_tlv_header = {
  .tag = PAYLOAD_REGION_TAG,
  .length = sizeof(struct payload_region),
  .version = PAYLOAD_REGION_VERSION,
};

static const struct payload_region global_regions[] = {
  {
    .header = region_tlv_header,
    .region_name = "region1",
    .region_offset = IMAGE_REGION_BASE,
    .region_size = 0x1000
  },
  {
    .header = region_tlv_header,
    .region_name = "region2",
    .region_offset = IMAGE_REGION_BASE + 0x1000,
    .region_size = 0x1000
  },
  {
    .header = region_tlv_header,
    .region_name = "region3",
    .region_offset = IMAGE_REGION_BASE + 0x2000,
    .region_size = 0x1000
  },
};

void load_descriptor(void *flash_adr, struct image_descriptor *descriptor) {

}

void write_descriptor(char *filename, struct payload_region *regions, size_t region_count) {
  struct image_descriptor desc;

  // Populate header
  desc.header.header.tag = PAYLOAD_DESCRIPTOR_HEADER_TAG;
  desc.header.header.length = sizeof(desc.header);
  desc.header.header.version = PAYLOAD_DESCRIPTOR_HEADER_VERSION;
  desc.header.descriptor_offset = 0;
  desc.header.descriptor_area_size = sizeof(desc.header) +
                                     sizeof(desc.region_info) +
                                     (region_count * sizeof(struct payload_region));

  // Populate region info
  desc.region_info.header.tag = PAYLOAD_REGION_INFO_TAG;
  desc.region_info.header.length = sizeof(desc.region_info);
  desc.region_info.header.version = PAYLOAD_REGION_INFO_VERSION;
  desc.region_info.region_count = region_count;
  desc.region_info.hash_type = HASH_SHA256;

  memcpy(desc.regions, regions, sizeof(struct payload_region) * region_count);
}

int main() {
  struct image_descriptor *desc;
  load_descriptor(DESCRIPTOR_FLASH_ADDR, desc);
}
