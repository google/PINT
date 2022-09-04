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

#ifndef SPDM_LITE_REQUESTER_REQUESTER_H_
#define SPDM_LITE_REQUESTER_REQUESTER_H_

#include <stdbool.h>
#include <stddef.h>

#include "spdm_lite/common/capabilities.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/session_types.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef int (*spdm_dispatch_request_fn)(void* ctx, bool is_secure_msg,
                                        const uint8_t* req, size_t req_size,
                                        uint8_t* rsp, size_t* rsp_size);

// Holds function pointers needed to perform crypto operations and communicate
// with the Responder.
typedef struct {
  SpdmCryptoSpec crypto_spec;
  spdm_dispatch_request_fn dispatch_fn;
  void* dispatch_ctx;  // Passed to `dispatch_fn`.
} SpdmDispatchRequestCtx;

// Used to stage encrypted requests and responses. Should be at least as large
// as `(max request or response size + SPDM_SECURE_MESSAGE_OVERHEAD)`.
typedef struct {
  uint8_t* data;
  size_t size;
} SpdmScratchSpace;

typedef struct {
  const SpdmDispatchRequestCtx* dispatch_ctx;
  SpdmScratchSpace scratch;
  SpdmCapabilities requester_caps;
  SpdmAsymPubKey requester_pub_key;
  void* requester_priv_key_ctx;
} SpdmRequesterSessionParams;

int spdm_establish_session(const SpdmRequesterSessionParams* requester_params,
                           SpdmSessionParams* session);

int spdm_dispatch_app_request(const SpdmDispatchRequestCtx* dispatch_ctx,
                              SpdmScratchSpace scratch_space,
                              SpdmSessionParams* session, uint16_t standard_id,
                              const uint8_t* vendor_id, size_t vendor_id_size,
                              const void* req, size_t req_size, void* rsp,
                              size_t* rsp_size);

// Will zero out `session` on success.
int spdm_end_session(const SpdmDispatchRequestCtx* dispatch_ctx,
                     SpdmScratchSpace scratch_space,
                     SpdmSessionParams* session);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_REQUESTER_REQUESTER_H_
