#ifndef __FMD_PARSE_H
#define __FMD_PARSE_H

#include "fmd/payload_descriptor.h"
#include "fmd/util.h"

int parse_descriptor(void *flash_addr, struct image_descriptor *descriptor);

#endif // __FMD_PARSE_H
