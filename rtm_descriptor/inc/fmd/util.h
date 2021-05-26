#ifndef _UTIL_H
#define _UTIL_H

#include "payload_descriptor.h"

#define MAX_REGION_COUNT 0xFF

#define FMD_SUCCESS 0x0
#define FMD_ERROR_INVALID_FORMAT 0x1
#define FMD_ERROR_INVALID_ARGUMENT 0x2
#define FMD_ERROR_UNKNOWN_VERSION 0x2
#define FMD_ERROR_UNKNOWN 0x2

struct image_descriptor {
  struct payload_descriptor_header header;
  struct payload_region_info region_info;
  struct payload_region regions[MAX_REGION_COUNT];
};

#endif // _UTIL_H
