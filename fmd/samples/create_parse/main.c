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

#include <string.h>
#include <stdio.h>

#include <fmd/payload_descriptor.h>
#include <fmd/generate.h>
#include <fmd/parse.h>
#include <fmd/util.h>

#define IMAGE_REGION_BASE 0x1000

#define ARRAYSIZE(x) (sizeof(x) / sizeof(*x))

static const struct tlv_header region_tlv_header = {
  .tag = PAYLOAD_REGION_TAG,
  .length = sizeof(struct payload_region),
  .version = PAYLOAD_REGION_VERSION,
};

static const struct payload_region global_regions[] = {
  {
    .tlv = region_tlv_header,
    .region_name = "region1",
    .region_offset = IMAGE_REGION_BASE,
    .region_size = 0x1000
  },
  {
    .tlv = region_tlv_header,
    .region_name = "region2",
    .region_offset = IMAGE_REGION_BASE + 0x1000,
    .region_size = 0x1000
  },
  {
    .tlv = region_tlv_header,
    .region_name = "region3",
    .region_offset = IMAGE_REGION_BASE + 0x2000,
    .region_size = 0x1000
  },
};

int main() {
  int rc;

  // Write a descriptor to a file
  struct image_descriptor desc;
  rc = create_descriptor(global_regions, ARRAYSIZE(global_regions), FMD_HASH_SHA256,
                         &desc);
  if (rc != FMD_SUCCESS) {
    printf("ERROR: Failed to create image descriptor, error code=%d\n", rc);
    return rc;
  }

  printf("Successfully generated an image descriptor!\n");

  // Read the descriptor back
  struct image_descriptor out_desc;
  rc = parse_descriptor(&desc, &out_desc);
  if (rc != FMD_SUCCESS) {
    printf("ERROR: Failed to parse image descriptor, error code=%d\n", rc);
    return rc;
  }

  printf("Successfully parsed the generated image descriptor!\n");

  return 0;
}
