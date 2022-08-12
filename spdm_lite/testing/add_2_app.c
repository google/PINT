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

#include "testing/add_2_app.h"

#include <string.h>

#include "common/crypto_types.h"

int Add2AppFn(const SpdmSessionId* session_id, const SpdmAsymPubKey* pub_key,
              uint16_t standard_id, const uint8_t* vendor_id,
              size_t vendor_id_size, const uint8_t* payload,
              size_t payload_size, uint8_t* output, size_t* output_size) {
  uint32_t number;

  if (payload_size != sizeof(number)) {
    return -1;
  }

  memcpy(&number, payload, sizeof(number));

  number += 2;

  uint16_t pub_key_size = spdm_get_asym_pub_key_size(pub_key->alg);

  const uint32_t rsp_size =
      sizeof(*session_id) + pub_key_size + sizeof(number);
  if (*output_size < rsp_size) {
    return -1;
  }

  memcpy(output, session_id, sizeof(*session_id));
  output += 4;

  memcpy(output, pub_key->data, pub_key_size);
  output += pub_key_size;

  memcpy(output, &number, sizeof(number));
  output += sizeof(number);

  *output_size = rsp_size;

  return 0;
}
