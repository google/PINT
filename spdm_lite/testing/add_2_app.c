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

int add_2_app_fn(const SpdmSessionId* session_id,
                 const SpdmNegotiatedAlgs* negotiated_algs,
                 const SpdmAsymPubKey* pub_key, uint16_t standard_id,
                 const uint8_t* vendor_id, size_t vendor_id_size,
                 const uint8_t* payload, size_t payload_size, uint8_t* output,
                 size_t* output_size) {
  Add2AppResponse rsp = {};

  if (payload_size != sizeof(rsp.num)) {
    return -1;
  }

  memcpy(&rsp.num, payload, sizeof(rsp.num));

  rsp.num += 2;

  rsp.session_id = *session_id;
  rsp.asym_sign_alg = negotiated_algs->asym_sign_alg;
  rsp.asym_verify_alg = negotiated_algs->asym_verify_alg;
  rsp.hash_alg = negotiated_algs->hash_alg;
  rsp.dhe_alg = negotiated_algs->dhe_alg;
  rsp.aead_alg = negotiated_algs->aead_alg;

  uint32_t rsp_size = sizeof(rsp) + pub_key->size;
  if (*output_size < rsp_size) {
    return -1;
  }

  memcpy(output, &rsp, sizeof(rsp));
  output += sizeof(rsp);

  memcpy(output, pub_key->data, pub_key->size);
  output += pub_key->size;

  *output_size = rsp_size;

  return 0;
}
