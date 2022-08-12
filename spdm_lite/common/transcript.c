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

#include "common/transcript.h"

#include <string.h>

#include "common/crypto.h"

int spdm_append_to_transcript(SpdmNegotiationTranscript* transcript,
                              const void* data, uint32_t size) {
  if (sizeof(transcript->data) - transcript->size < size) {
    return -1;
  }

  memcpy(transcript->data + transcript->size, data, size);
  transcript->size += size;

  return 0;
}

int spdm_initialize_transcript_hash(
    const SpdmCryptoSpec* crypto_spec, SpdmHashAlgorithm alg,
    const SpdmNegotiationTranscript* transcript,
    SpdmHash* transcript_hash) {
  int rc = spdm_initialize_hash_struct(crypto_spec, alg, transcript_hash);
  if (rc != 0) {
    return rc;
  }

  spdm_initialize_hash(transcript_hash);
  spdm_extend_hash(transcript_hash, transcript->data, transcript->size);

  return 0;
}
