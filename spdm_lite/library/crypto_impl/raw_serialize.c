// Copyright 2022 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "spdm_lite/crypto_impl/raw_serialize.h"

#include <string.h>

#include "spdm_lite/common/crypto_types.h"

int spdm_raw_serialize_asym_key(SpdmAsymAlgorithm asym_alg,
                                SpdmHashAlgorithm hash_alg, const uint8_t* in,
                                uint16_t in_size, uint8_t* out,
                                uint16_t* out_size) {
  if (*out_size < in_size) {
    return -1;
  }

  memcpy(out, in, in_size);

  *out_size = in_size;

  return 0;
}
