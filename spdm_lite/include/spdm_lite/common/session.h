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

#ifndef SPDM_LITE_COMMON_SESSION_H_
#define SPDM_LITE_COMMON_SESSION_H_

#include <stdint.h>

#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/utils.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

int spdm_generate_session_params(const SpdmCryptoSpec* spec,
                                 SpdmDheAlgorithm alg,
                                 SpdmSelfKeyExchangeParams* my_params);

void spdm_generate_session_id(SPDMRole my_role, const uint8_t my_part[2],
                              const uint8_t their_part[2],
                              SpdmSessionId* session_id);

// `header` must contain sizeof(SPDM_SecuredMessageRecord) bytes and precede
// `input`, which must precede `footer`.
int spdm_encrypt_secure_message(const SpdmCryptoSpec* spec,
                                const SpdmSessionId* session_id,
                                uint64_t seq_num, const SpdmAeadKeys* keys,
                                uint8_t* header, buffer input,
                                byte_writer* footer);

// `message` is updated to point to the decrypted-in-place plaintext message.
int spdm_decrypt_secure_message(const SpdmCryptoSpec* spec,
                                const SpdmSessionId* session_id,
                                uint64_t seq_num, const SpdmAeadKeys* keys,
                                buffer* message);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_SESSION_H_
