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

#ifndef SPDM_LITE_REQUESTER_SEND_REQUEST_H_
#define SPDM_LITE_REQUESTER_SEND_REQUEST_H_

#include <stdbool.h>

#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/requester/requester.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// The response is stored in `dispatch_ctx->scratch_buffer`
int spdm_send_request(const SpdmDispatchRequestCtx* dispatch_ctx,
                      bool is_secure_msg, buffer req, buffer* rsp);

// The response is stored in `dispatch_ctx->scratch_buffer`
int spdm_send_secure_request(const SpdmDispatchRequestCtx* dispatch_ctx,
                             SpdmSessionParams* session, SpdmSessionPhase phase,
                             buffer req, buffer* rsp);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_REQUESTER_SEND_REQUEST_H_
