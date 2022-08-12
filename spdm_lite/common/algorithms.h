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

#ifndef SPDM_LITE_COMMON_ALGORITHMS_H_
#define SPDM_LITE_COMMON_ALGORITHMS_H_

#include <stdbool.h>

#include "common/crypto_types.h"
#include "common/messages.h"
#include "common/utils.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Filter out signing algs that our key doesn't support.
void spdm_get_my_supported_algs(const SpdmCryptoSpec* crypto_spec,
                                const SpdmAsymPubKey* my_pub_key,
                                SpdmSupportedAlgs* supported_algs);

int spdm_get_their_supported_algs(const SPDM_AsymHashAlgs* asym_hash_algs,
                                  buffer alg_structs,
                                  uint32_t alg_structs_count, bool is_resp,
                                  SpdmSupportedAlgs* supported_algs);

void spdm_get_negotiated_algs(const SpdmSupportedAlgs* my_algs,
                              const SpdmSupportedAlgs* their_algs,
                              SpdmSupportedAlgs* common_algs,
                              SpdmNegotiatedAlgs* negotiated_algs);

void spdm_write_algs(const SpdmSupportedAlgs* algs, bool is_resp,
                     SPDM_AsymHashAlgs* algs_msg, SPDM_AlgStruct_DHE* dhe_msg,
                     SPDM_AlgStruct_AEAD* aead_msg,
                     SPDM_AlgStruct_BaseAsym* asym_msg,
                     SPDM_AlgStruct_KeySchedule* keysched_msg);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_ALGORITHMS_H_
