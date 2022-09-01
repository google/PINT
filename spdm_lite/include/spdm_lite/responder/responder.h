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

#ifndef SPDM_LITE_RESPONDER_RESPONDER_H_
#define SPDM_LITE_RESPONDER_RESPONDER_H_

#include <stddef.h>

#include "spdm_lite/common/capabilities.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/transcript.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/*
    .-----------.                            .-----------.
    | Requester |                            | Responder |     [Responder state]
    .-----------.                            .-----------.
          |                                        | WAITING_FOR_GET_VERSION
          |--------------GET_VERSION-------------->|
          |<-----------------VERSION---------------|
          |                                        | WAITING_FOR_GET_CAPABILITIES
          |-----------GET_CAPABILITIES------------>|
          |<--------------CAPABILITIES-------------|
          |                                        | WAITING_FOR_NEGOTIATE_ALGORITHMS
          |----------NEGOTIATE_ALGORITHMS--------->|
          |<-------------------ALGORITHMS----------|
          |                                        | WAITING_FOR_KEY_EXCHANGE
          |-------------GET_PUB_KEY--------------->|
          |<------------GET_PUB_KEY_RSP------------|
          |                                        |
          |------------KEY_EXCHANGE--------------->|
          |<-----------KEY_EXCHANGE_RSP------------|
          |                                        | MUTUAL_AUTH_NEED_REQUESTER_KEY
          |-------------GIVE_PUB_KEY-------------->|
          |<------------GIVE_PUB_KEY_RSP-----------|
          |                                        | MUTUAL_AUTH_WAITING_FOR_FINISH
          |----------------FINISH----------------->|
          |<---------------FINISH_RSP--------------|
          |                                        | SESSION_ESTABLISHED
*/

typedef enum {
  STATE_WAITING_FOR_GET_VERSION = 0,
  STATE_WAITING_FOR_GET_CAPABILITIES,
  STATE_WAITING_FOR_NEGOTIATE_ALGORITHMS,
  STATE_WAITING_FOR_KEY_EXCHANGE,
  STATE_MUTUAL_AUTH_NEED_REQUESTER_KEY,
  STATE_MUTUAL_AUTH_WAITING_FOR_FINISH,
  STATE_SESSION_ESTABLISHED,
} SpdmResponderState;

typedef int (*spdm_app_dispatch_request_fn)(
    const SpdmSessionInfo* session_info, uint16_t standard_id,
    const uint8_t* vendor_id, size_t vendor_id_size, const uint8_t* payload,
    size_t payload_size, uint8_t* output, size_t* output_size);

typedef struct {
  SpdmSessionParams params;
  SpdmHash transcript_hash;
} SpdmResponderSession;

typedef struct {
  // Populated at initialization
  SpdmResponderState state;
  SpdmCryptoSpec crypto_spec;
  SpdmCapabilities responder_caps;
  SpdmAsymPubKey responder_pub_key;
  void* responder_priv_key_ctx;
  spdm_app_dispatch_request_fn app_dispatch_fn;

  SpdmNegotiationTranscript negotiation_transcript;

  // Populated from `GET_CAPABILITIES`
  SpdmCapabilities requester_caps;

  // Populated from `NEGOTIATE_ALGORITHMS`
  SpdmNegotiatedAlgs negotiated_algs;

  // Populated from `KEY_EXCHANGE`
  SpdmResponderSession session;
} SpdmResponderContext;

int spdm_initialize_responder_context(
    SpdmResponderContext* ctx, const SpdmCryptoSpec* crypto_spec,
    SpdmCapabilities responder_caps, const SpdmAsymPubKey* responder_pub_key,
    void* responder_priv_key_ctx, spdm_app_dispatch_request_fn app_dispatch_fn);

// Top-level request dispatcher. Ensures the version matches before invoking one
// of the state-specific handlers. `is_secure` indicates whether the incoming
// command is an encrypted SPDM request.
int spdm_dispatch_request(SpdmResponderContext* ctx, bool is_secure,
                          const uint8_t* req, size_t req_size, uint8_t* rsp,
                          size_t* rsp_size);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_RESPONDER_RESPONDER_H_
