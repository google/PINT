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

#ifndef SPDM_LITE_COMMON_TRANSCRIPT_H_
#define SPDM_LITE_COMMON_TRANSCRIPT_H_

#include <stdint.h>

#include "common/crypto_types.h"
#include "common/messages.h"

#define SPDM_MAX_VERSION_NUMBER_ENTRIES 16

// A request/response without extended algorithms doesn't exceed 52 bytes.
#define SPDM_MAX_ALG_MSG_SIZE 80

#define SPDM_VERSION_CAPABILITIES_TRANSCRIPT_SIZE                        \
  (sizeof(SPDM_GET_VERSION) + sizeof(SPDM_VERSION) +                     \
   (SPDM_MAX_VERSION_NUMBER_ENTRIES * sizeof(SPDM_VersionNumberEntry)) + \
   sizeof(SPDM_GET_CAPABILITIES) + sizeof(SPDM_CAPABILITIES) +           \
   SPDM_MAX_ALG_MSG_SIZE + SPDM_MAX_ALG_MSG_SIZE)

typedef struct {
  uint32_t size;
  uint8_t data[SPDM_VERSION_CAPABILITIES_TRANSCRIPT_SIZE];
} SpdmNegotiationTranscript;

int spdm_append_to_transcript(SpdmNegotiationTranscript* transcript,
                              const void* data, uint32_t size);

int spdm_initialize_transcript_hash(
    const SpdmCryptoSpec* crypto_spec, SpdmHashAlgorithm alg,
    const SpdmNegotiationTranscript* transcript,
    SpdmHash* transcript_hash);

#endif  // SPDM_LITE_COMMON_TRANSCRIPT_H_
