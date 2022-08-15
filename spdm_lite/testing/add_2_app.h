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

#ifndef SPDM_LITE_TESTING_ADD_2_APP_H_
#define SPDM_LITE_TESTING_ADD_2_APP_H_

#include "common/crypto_types.h"
#include "common/defs.h"
#include "common/session_types.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef struct {
  SpdmSessionId session_id;
  uint8_t asym_sign_alg;
  uint8_t asym_verify_alg;
  uint8_t hash_alg;
  uint8_t dhe_alg;
  uint8_t aead_alg;
  uint32_t num;
  // uint8_t pub_key[...]
} PACKED Add2AppResponse;

// App that echoes back the session ID, negotiated algs, and public key, as well
// as the given uint32 double-incremented.
int add_2_app_fn(const SpdmSessionId* session_id,
                 const SpdmNegotiatedAlgs* negotiated_algs,
                 const SpdmAsymPubKey* pub_key, uint16_t standard_id,
                 const uint8_t* vendor_id, size_t vendor_id_size,
                 const uint8_t* payload, size_t payload_size, uint8_t* output,
                 size_t* output_size);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_TESTING_ADD_2_APP_H_
