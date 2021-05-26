#ifndef __PAYLOAD_DESCRIPTOR_H
#define __PAYLOAD_DESCRIPTOR_H

#include <stddef.h>
#include <stdint.h>

/**
 *  ---------------------------------- Layout ----------------------------------
 *  |                 struct payload_descriptor_header                         |
 *  ----------------------------------------------------------------------------
 *  |                     struct payload_region_info                           |
 *  ----------------------------------------------------------------------------
 *  |         struct payload_region[payload_region_info.region_count]          |
 *  ----------------------------------------------------------------------------
 */

#define FMD_HASH_SHA1 0
#define FMD_HASH_SHA256 1

#define PAYLOAD_DESCRIPTOR_HEADER_TAG 0
#define PAYLOAD_REGION_INFO_TAG 1
#define PAYLOAD_REGION_TAG 2

#define PAYLOAD_REGION_INFO_VERSION 1
#define PAYLOAD_REGION_VERSION 1
#define PAYLOAD_DESCRIPTOR_HEADER_VERSION 1

struct tlv_header {
  uint32_t tag;
  uint16_t length;
  uint8_t version; // version of the struct in which this header is embedded.
};

struct payload_region_info {
  struct tlv_header tlv;

  uint32_t region_count;

  uint32_t hash_type;
};

struct payload_region {
  struct tlv_header tlv;

  uint8_t region_name[32];  /* null-terminated ASCII string */

  uint32_t region_offset;

  uint32_t region_size;
};

struct payload_descriptor_header {
  struct tlv_header tlv;

  /* The offset is relative to the start of the image data. */
  uint32_t descriptor_offset;

  /* Includes this struct as well as the auxiliary structs. This many bytes
   * will be skipped when computing the hash of the region this struct
   * resides in. Tail padding is allowed but must be all 0xff's.
   */
  uint32_t descriptor_area_size;
};

#endif // __PAYLOAD_DESCRIPTOR_H
