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

#ifndef SPDM_LITE_COMMON_SIGN_H_
#define SPDM_LITE_COMMON_SIGN_H_

#include <stdint.h>

#include "common/crypto_types.h"
#include "common/utils.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

int spdm_sign(const SpdmCryptoSpec* crypto_spec, SpdmAsymAlgorithm alg,
              void* priv_key_ctx, SPDMRole my_role,
              const SpdmHashResult* message_hash, const char* context,
              uint8_t* out, uint32_t out_len);

int spdm_verify(const SpdmCryptoSpec* crypto_spec,
                const SpdmAsymPubKey* pub_key, SPDMRole signer_role,
                const SpdmHashResult* message_hash, const char* context,
                const uint8_t* sig, uint32_t sig_len);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_SIGN_H_
