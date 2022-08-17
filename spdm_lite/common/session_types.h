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

#ifndef SPDM_LITE_COMMON_SESSION_TYPES_H_
#define SPDM_LITE_COMMON_SESSION_TYPES_H_

#include <stdint.h>

#include "common/crypto_types.h"
#include "common/messages.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef struct {
  uint8_t my_session_id_part[2];
  SpdmDhePrivKey my_priv_key;
  SpdmDhePubKey my_pub_key;
} SpdmSelfKeyExchangeParams;

typedef struct {
  uint8_t id[4];
} SpdmSessionId;

typedef struct {
  SpdmSessionId session_id;
  SpdmNegotiatedAlgs negotiated_algs;
  SpdmAsymPubKey peer_pub_key;
} SpdmSessionInfo;

typedef struct {
  SpdmSessionInfo info;
  SpdmDheSecret shared_key;
  SpdmHashResult th_1;
  SpdmHashResult th_2;
  uint64_t req_seq_num;
  uint64_t rsp_seq_num;
} SpdmSessionParams;

typedef enum {
  SPDM_NO_SESSION = 0,
  SPDM_HANDSHAKE_PHASE,
  SPDM_DATA_PHASE,
} SpdmSessionPhase;

#define SPDM_MAX_SECURE_MESSAGE_RAND_LEN 16
#define SPDM_MAX_SECURE_MESSAGE_FOOTER_LEN \
  (SPDM_MAX_SECURE_MESSAGE_RAND_LEN + AES_GCM_MAC_SIZE)
#define SPDM_SECURE_MESSAGE_OVERHEAD \
  (sizeof(SPDM_SecuredMessageRecord) + SPDM_MAX_SECURE_MESSAGE_FOOTER_LEN)

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_SESSION_TYPES_H_
