#ifndef __FMD_GENERATE_H
#define __FMD_GENERATE_H

#include "fmd/payload_descriptor.h"
#include "fmd/util.h"

#include <stddef.h>

int create_descriptor(const struct payload_region* regions, size_t region_count,
                      int hash_type, struct image_descriptor *out);

#endif // __FMD_GENERATE_H
