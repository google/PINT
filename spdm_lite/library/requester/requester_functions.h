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

#ifndef SPDM_LITE_LIBRARY_REQUESTER_REQUESTER_FUNCTIONS_H_
#define SPDM_LITE_LIBRARY_REQUESTER_REQUESTER_FUNCTIONS_H_

#include "spdm_lite/common/capabilities.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/transcript.h"
#include "spdm_lite/requester/requester.h"

// Holds data needed to establish a session with a Responder.
typedef struct {
  const SpdmRequesterSessionParams* params;

  SpdmNegotiationTranscript negotiation_transcript;

  SpdmHash transcript_hash;

  // Populated from `CAPABILITIES`
  SpdmCapabilities responder_caps;
} SpdmRequesterContext;

int spdm_get_version(SpdmRequesterContext* ctx);
int spdm_get_capabilities(SpdmRequesterContext* ctx);
int spdm_negotiate_algorithms(SpdmRequesterContext* ctx,
                              SpdmSessionParams* session);
int spdm_get_pub_key(SpdmRequesterContext* ctx, SpdmSessionParams* session);
int spdm_key_exchange(SpdmRequesterContext* ctx, SpdmSessionParams* session);
int spdm_give_pub_key(SpdmRequesterContext* ctx, SpdmSessionParams* session);
int spdm_finish(SpdmRequesterContext* ctx, SpdmSessionParams* session);

#endif  // SPDM_LITE_LIBRARY_REQUESTER_REQUESTER_FUNCTIONS_H_
