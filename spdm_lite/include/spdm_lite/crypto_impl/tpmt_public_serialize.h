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

#ifndef SPDM_LITE_CRYPTO_IMPL_TPMT_PUBLIC_SERIALIZE_H_
#define SPDM_LITE_CRYPTO_IMPL_TPMT_PUBLIC_SERIALIZE_H_

#include "spdm_lite/common/crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Handlers for serializing and deserializing an SPDM-Lite public key as a
// marshalled TPMT_PUBLIC.

// `in` is expected to be a raw byte buffer holding an SPDM-Lite internal
// representation of a public key, adhering to `asym_alg` and `hash_alg`. `out`
// will hold a marshalled TPMT_PUBLIC. `*out_size` should be at least
// sizeof(TPMT_PUBLIC), as that is the upper limit on the size of a marshalled
// instance.
int spdm_serialize_asym_pub_to_tpmt_public(SpdmAsymAlgorithm asym_alg,
                                           SpdmHashAlgorithm hash_alg,
                                           const uint8_t* in, uint16_t in_size,
                                           uint8_t* out, uint16_t* out_size);

// `in` is expected to be a marshalled TPMT_PUBLIC. `out` is expected to point
// to a raw byte buffer for an SPDM-Lite internal representation of a public
// key, adhering to `asym_alg` and `hash_alg`.
int spdm_deserialize_asym_pub_from_tpmt_public(SpdmAsymAlgorithm asym_alg,
                                               SpdmHashAlgorithm hash_alg,
                                               const uint8_t* in,
                                               uint16_t in_size, uint8_t* out,
                                               uint16_t* out_size);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_CRYPTO_IMPL_TPMT_PUBLIC_SERIALIZE_H_
