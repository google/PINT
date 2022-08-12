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

#ifndef SPDM_LITE_COMMON_KEY_SCHEDULE_H_
#define SPDM_LITE_COMMON_KEY_SCHEDULE_H_

#include <stdint.h>

#include "common/crypto_types.h"
#include "common/session_types.h"
#include "common/utils.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef struct {
  SpdmHashResult request_direction;
  SpdmHashResult response_direction;
} SpdmMessageSecrets;

typedef struct {
  SpdmAeadKeys req_keys;
  SpdmAeadKeys rsp_keys;
} SpdmSessionAeadKeys;

int spdm_generate_message_secrets(const SpdmCryptoSpec* crypto_spec,
                                  const SpdmSessionParams* session,
                                  SpdmSessionPhase phase,
                                  SpdmMessageSecrets* secrets);

int spdm_generate_finished_key(const SpdmCryptoSpec* crypto_spec,
                               SPDMRole originator,
                               const SpdmMessageSecrets* secrets,
                               SpdmHashResult* key);

int spdm_generate_aead_keys(const SpdmCryptoSpec* crypto_spec,
                            SpdmAeadAlgorithm alg,
                            const SpdmMessageSecrets* secrets,
                            uint64_t req_seq_num, uint64_t rsp_seq_num,
                            SpdmSessionAeadKeys* keys);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_KEY_SCHEDULE_H_
